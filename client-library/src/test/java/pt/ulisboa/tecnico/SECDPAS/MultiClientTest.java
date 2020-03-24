package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.Test;
import org.junit.experimental.ParallelComputer;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import java.security.*;

import static org.junit.Assert.*;

public class MultiClientTest {

    private static PublicKey pub1;

    @Test
    public void runAllTests(){
        Class<?>[] classes = {Client1.class/*, Client5.class, Client2.class, Client3.class, Client4.class*/};

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
        /* post and read */
        private static ClientLibrary lib;
        @AfterClass
        public static void cleanUp(){
            lib.cleanPosts();
            lib.cleanGeneralPosts();
            lib.shutDown();
        }
        @Test
        public void run(){
            int num = 1;
            Boolean result = true;
            try{
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                pub1 = kp.getPublic();
                PrivateKey priv = kp.getPrivate();

                lib = new ClientLibrary("localhost", 8080, pub1, priv);

                lib.register();

                lib.setupConnection();

                for(int i=0; i<num; i++){
                    lib.post(("message" + i).toCharArray());
                    System.out.println("T1 post " + i);
                }

                Announcement[] announcements = lib.read(pub1, 0);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    System.out.println("T1 read " + i);

                    if(!result) break;
                }
                System.out.println("SECOND READ");
                kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                kp = kpg.genKeyPair();
                PublicKey pub = kp.getPublic();
                priv = kp.getPrivate();

                ClientLibrary lib2 = new ClientLibrary("localhost", 8080, pub, priv);

                lib2.register();

                lib2.setupConnection();

                announcements = lib2.read(pub1, 0);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    System.out.println("T100 read " + i);

                    if(!result) break;
                }

                System.out.println("\n\nT1 done");
                assertTrue(result);

            }catch (NoSuchAlgorithmException | InvalidArgumentException | ClientNotRegisteredException | ClientAlreadyRegisteredException | CertificateInvalidException e){
                System.out.println(e.getMessage());
            }
        }
    }

    public static class Client2{
        /* post and read */
        private static ClientLibrary lib;
        @AfterClass
        public static void cleanUp(){
            lib.cleanPosts();
            lib.cleanGeneralPosts();
            lib.shutDown();
        }
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

                lib.register();

                lib.setupConnection();

                for(int i=0; i<num; i++){
                    lib.post(("message" + i).toCharArray());
                    System.out.println("T2 post " + i);
                }

                Announcement[] announcements = lib.read(pub, 0);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));

                    System.out.println("T2 read " + i);

                    if(!result) break;
                }
                System.out.println("\n\nT2 done");

                assertTrue(result);

            }catch (NoSuchAlgorithmException | InvalidArgumentException | ClientNotRegisteredException | ClientAlreadyRegisteredException | CertificateInvalidException e){
                System.out.println(e.getMessage());
            }
        }

    }

    public static class Client3{
        /* post general and read general */
        private static ClientLibrary lib;
        @AfterClass
        public static void cleanUp(){
            lib.cleanPosts();
            lib.cleanGeneralPosts();
            lib.shutDown();
        }
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

                lib.register();

                lib.setupConnection();

                for(int i=0; i<num; i++){
                    lib.postGeneral(("message" + i).toCharArray());
                    System.out.println("T3 post " + i);
                }

                Announcement[] announcements = lib.readGeneral(0);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    System.out.println("T3 read " + i);

                    if(!result) break;
                }
                System.out.println("\n\nT3 done");

                assertTrue(result);

            }catch (NoSuchAlgorithmException | InvalidArgumentException | ClientNotRegisteredException | ClientAlreadyRegisteredException | CertificateInvalidException e){
                System.out.println(e.getMessage());
            }
        }
    }

    public static class Client4{
        /* read general */
        private static ClientLibrary lib;
        @AfterClass
        public static void cleanUp(){
            lib.cleanPosts();
            lib.cleanGeneralPosts();
            lib.shutDown();
        }
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

                lib.register();

                lib.setupConnection();

                Thread.sleep(3000);

                Announcement[] announcements = lib.readGeneral(1);

                System.out.println(announcements);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    System.out.println("T4 read " + i);

                    if(!result) break;
                }

                System.out.println("\n\nT4 done");

                assertTrue(result);

            }catch (InterruptedException | NoSuchAlgorithmException | InvalidArgumentException | ClientNotRegisteredException | ClientAlreadyRegisteredException | CertificateInvalidException e){
                System.out.println(e.getMessage());
            }
        }
    }

    public static class Client5{
        /* post and read */
        private static ClientLibrary lib;
        @AfterClass
        public static void cleanUp(){
            lib.cleanPosts();
            lib.cleanGeneralPosts();
            lib.shutDown();
        }
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

                lib.register();

                lib.setupConnection();

                Thread.sleep(1500);

                Announcement[] announcements = lib.read(pub1, 0);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));

                    System.out.println("T5 read " + i);

                    if(!result) break;
                }
                System.out.println("\n\nT5 done");

                assertTrue(result);

            }catch (InterruptedException | NoSuchAlgorithmException | InvalidArgumentException | ClientNotRegisteredException | ClientAlreadyRegisteredException | CertificateInvalidException e){
                System.out.println(e.getMessage());
            }
        }

    }
}
