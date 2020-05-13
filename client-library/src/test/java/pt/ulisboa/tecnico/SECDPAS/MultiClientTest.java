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
        Class<?>[] classes = {Client1.class, Client2.class, Client3.class};

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
        /* post general */
        private static ClientLibrary lib;
        @Test
        public void run(){
            int num = 25;
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

                Announcement[] announcements = lib.readGeneral(num);

                assertEquals(num, announcements.length);

            } catch (NoSuchAlgorithmException | InvalidArgumentException | CertificateInvalidException e){
                System.out.println("client3: " + e.getMessage());
            }
        }
    }

    public static class Client2{
        /* post general */
        private static ClientLibrary lib;
        @Test
        public void run(){
            int num = 25;
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
                Announcement[] announcements = lib.readGeneral(num);

                assertEquals(num, announcements.length);

            } catch (NoSuchAlgorithmException | InvalidArgumentException | CertificateInvalidException e){
                System.out.println("client4: " + e.getMessage());
            }
        }
    }

    public static class Client3{
        /* read general */
        private static ClientLibrary lib;
        @Test
        public void run(){
            int num = 25;
            try{
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(2048);
                KeyPair kp = kpg.genKeyPair();
                PublicKey pub = kp.getPublic();
                PrivateKey priv = kp.getPrivate();

                lib = new ClientLibrary("localhost", 8080, pub, priv);
                list.add(lib);

                lib.register();

                Thread.sleep(num * 1100);

                Announcement[] announcements = lib.readGeneral(0);

                assertEquals(num*2, announcements.length);

            } catch (InterruptedException | NoSuchAlgorithmException | InvalidArgumentException | CertificateInvalidException e){
                System.out.println("client5: " + e.getMessage());
            }
        }
    }
}
