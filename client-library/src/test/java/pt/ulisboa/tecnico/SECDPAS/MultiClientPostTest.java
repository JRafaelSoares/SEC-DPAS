package pt.ulisboa.tecnico.SECDPAS;

import org.junit.AfterClass;
import org.junit.Test;
import org.junit.experimental.ParallelComputer;
import org.junit.runner.JUnitCore;
import org.junit.runner.Result;
import org.junit.runner.notification.Failure;

import java.net.StandardSocketOptions;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class MultiClientPostTest {

    private static List<ClientLibrary> list = new ArrayList<>();
    private static PublicKey pub1;
    private static CountDownLatch latch = new CountDownLatch(2);


    @AfterClass
    public static void cleanUp(){
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
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
        /* post and read on its own */
        private static ClientLibrary lib;

        @Test
        public void run(){
            int num = 25;
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
                latch.countDown();
                Announcement[] announcements = lib.read(pub1, 0);
                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++){
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    if(!result) break;
                }
                assertTrue(result);

            } catch (NoSuchAlgorithmException | InvalidArgumentException | CertificateInvalidException e){
                System.out.println("client1: " + e.getMessage());
            }
        }
    }

    public static class Client2{
        /* post and read on its own */
        private static ClientLibrary lib;

        @Test
        public void run(){
            int num = 25;
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
                latch.countDown();

                Announcement[] announcements = lib.read(pub, 0);

                assertEquals(num, announcements.length);

                for(int i=0; i<announcements.length; i++) {
                    result = ("message" + i).equals(new String(announcements[i].getPost()));
                    if (!result) break;
                }

                assertTrue(result);

            } catch (NoSuchAlgorithmException | InvalidArgumentException | CertificateInvalidException e){
                System.out.println("client2: " + e.getMessage());
            }
        }

    }

    public static class Client3{
        /* read posts */
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
                    lib.read(pub1, 0);
                }
                latch.await();
                Announcement[] announcements = lib.read(pub1, 0);

                assertEquals(num, announcements.length);

            } catch (NoSuchAlgorithmException | InvalidArgumentException | CertificateInvalidException e){
                System.out.println("client3: " + e.getMessage());
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}
