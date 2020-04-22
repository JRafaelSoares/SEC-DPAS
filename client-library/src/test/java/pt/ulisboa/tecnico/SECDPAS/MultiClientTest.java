package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.Test;
import org.junit.experimental.ParallelComputer;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import java.security.*;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

public class MultiClientTest {

    private static List<ClientLibrary> list = new ArrayList<>();
    private static PublicKey pub1;

    @AfterClass
    public static void cleanUp(){
        for(ClientLibrary lib : list){
            lib.cleanPosts();
            lib.cleanGeneralPosts();
            lib.shutDown();
        }
    }

    @Test
    public void runAllTests(){
        Class<?>[] classes = {Client1.class, Client2.class, Client3.class, Client4.class, Client5.class};

        Result result = JUnitCore.runClasses(new ParallelComputer(true, true), classes);

        if(!result.wasSuccessful()){
            for(Failure f : result.getFailures()){
                System.out.println("Failure: " + f.getTrace());
            }
        }else{
            assertTrue(true);
        }
    }

    public static class Client1{
        /* post and read on its own */
        private static ClientLibrary lib;

        @Test
        public void run(){
            int num = 100;
            Boolean result = true;
            try{
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                pub1 = kp.getPublic();
                PrivateKey priv = kp.getPrivate();

                lib = new ClientLibrary("localhost", 8080, pub1, priv);
                list.add(lib);

                lib.register();

                for(int i=0; i<num; i++){
                    lib.post(("message" + i).toCharArray());
                }

                Announcement[] announcements = lib.read(pub1, 0);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    if(!result) break;
                }
                //System.out.println("\n\nT1 done");
                assertTrue(result);

            } catch (NoSuchAlgorithmException | InvalidArgumentException | ComunicationException | CertificateInvalidException e){
                System.out.println("client1: " + e.getMessage());
            }
        }
    }

    public static class Client2{
        /* post and read on its own */
        private static ClientLibrary lib;

        @Test
        public void run(){
            int num = 100;
            Boolean result = true;
            try{
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                PublicKey pub = kp.getPublic();
                PrivateKey priv = kp.getPrivate();

                lib = new ClientLibrary("localhost", 8080, pub, priv);
                list.add(lib);

                lib.register();

                for(int i=0; i<num; i++){
                    lib.post(("message" + i).toCharArray());
                }

                Announcement[] announcements = lib.read(pub, 0);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++) {
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    if (!result) break;
                }

                //System.out.println("\n\nT2 done");

                assertTrue(result);

            } catch (NoSuchAlgorithmException | InvalidArgumentException | ComunicationException | CertificateInvalidException e){
                System.out.println("client2: " + e.getMessage());
            }
        }

    }

    public static class Client3{
        /* post general and read general */
        private static ClientLibrary lib;
        @Test
        public void run(){
            int num = 100;
            try{
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                PublicKey pub = kp.getPublic();
                PrivateKey priv = kp.getPrivate();

                lib = new ClientLibrary("localhost", 8080, pub, priv);
                list.add(lib);

                lib.register();

                for(int i=0; i<num; i++){
                    lib.postGeneral(("message" + i).toCharArray());
                }

                Announcement[] announcements = lib.readGeneral(100);

                assertEquals(num, announcements.length);

                //System.out.println("\n\nT3 done");

            } catch (NoSuchAlgorithmException | InvalidArgumentException | ComunicationException | CertificateInvalidException e){
                System.out.println("client3: " + e.getMessage());
            }
        }
    }

    public static class Client4{
        /* post general and read general */
        private static ClientLibrary lib;
        @Test
        public void run(){
            int num = 100;
            try{
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                PublicKey pub = kp.getPublic();
                PrivateKey priv = kp.getPrivate();

                lib = new ClientLibrary("localhost", 8080, pub, priv);
                list.add(lib);

                lib.register();

                for(int i=0; i<num; i++){
                    lib.postGeneral(("message" + i).toCharArray());
                }

                Announcement[] announcements = lib.readGeneral(100);

                assertEquals(num, announcements.length);

                //System.out.println("\n\nT4 done");

            } catch (NoSuchAlgorithmException | InvalidArgumentException | ComunicationException | CertificateInvalidException e){
                System.out.println("client4: " + e.getMessage());
            }
        }
    }

    public static class Client5{
        /* read general */
        private static ClientLibrary lib;
        @Test
        public void run(){
            int num = 100;
            try{
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                PublicKey pub = kp.getPublic();
                PrivateKey priv = kp.getPrivate();

                lib = new ClientLibrary("localhost", 8080, pub, priv);
                list.add(lib);

                lib.register();

                Thread.sleep(15000);

                Announcement[] announcements = lib.readGeneral(0);

                assertEquals(num*2, announcements.length);

                //System.out.println("\n\nT5 done");

            } catch (InterruptedException | NoSuchAlgorithmException | InvalidArgumentException | ComunicationException | CertificateInvalidException e){
                System.out.println("client5: " + e.getMessage());
            }
        }
    }

    public static class Client6{
        /* read Client1 */
        private static ClientLibrary lib;
        @Test
        public void run(){
            int num = 100;
            Boolean result = true;
            try{
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                PublicKey pub = kp.getPublic();
                PrivateKey priv = kp.getPrivate();

                lib = new ClientLibrary("localhost", 8080, pub, priv);
                list.add(lib);

                lib.register();

                Thread.sleep(15000);

                Announcement[] announcements = lib.read(pub1, 0);

                assertEquals(num*2, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    if(!result) break;
                }

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    if(!result) break;
                }

                //System.out.println("\n\nT6 done");

                assertTrue(result);

            } catch (InterruptedException | NoSuchAlgorithmException | InvalidArgumentException | ComunicationException | CertificateInvalidException e){
                System.out.println("client6: " + e.getMessage());
            }
        }

    }
}
