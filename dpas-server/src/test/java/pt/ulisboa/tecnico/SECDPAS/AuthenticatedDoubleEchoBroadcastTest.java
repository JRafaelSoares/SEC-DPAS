package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Longs;
import com.google.common.util.concurrent.FutureCallback;
import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.stubbing.Answer;

import java.security.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.fail;
import static org.mockito.Mockito.*;


public class AuthenticatedDoubleEchoBroadcastTest {

    private static int numServers;
    private static int minResponses;
    private static int postFreshness;
    private static int postGeneralFreshness;
    private static DPASServiceImpl[] servers;
    private static AuthenticatedPerfectLink[] serverPerfectLinks;
    private static PublicKey clientPublicKey;
    private static PrivateKey clientPrivateKey;

    private static final boolean seeBehaviour = false;

    @BeforeClass
    public static void setUp() {
        try {
            int numFaults = 1;
            numServers = 3 * numFaults + 1;

            minResponses = (int)Math.ceil(((double)numServers + numFaults)/2);

            postFreshness = 0;
            postGeneralFreshness = 0;

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(4096);
            KeyPair kp = kpg.genKeyPair();
            clientPublicKey = kp.getPublic();
            clientPrivateKey = kp.getPrivate();

            PublicKey[] serverPublicKeys = new PublicKey[numServers];
            PrivateKey[] serverPrivateKeys = new PrivateKey[numServers];
            serverPerfectLinks = new AuthenticatedPerfectLink[numServers];
            servers = new DPASServiceImpl[numServers];

            //Stub and certificate for each server
            for (int server = 0; server < numServers; server++) {
                kp = kpg.genKeyPair();
                PublicKey publicKey = kp.getPublic();
                PrivateKey privateKey = kp.getPrivate();

                serverPublicKeys[server] = publicKey;
                serverPrivateKeys[server] = privateKey;
                serverPerfectLinks[server] = mock(AuthenticatedPerfectLink.class);

                int finalServer = server;
                doAnswer((Answer<Void>) invocation -> {
                    RequestType request = (RequestType) invocation.getArguments()[0];

                    if(request.getId().equals("Echo")){
                        new Thread(() -> servers[finalServer].echo((Contract.EchoRequest) request.getRequest(), new StreamObserver<>() {
                            @Override
                            public void onNext(Contract.EchoReadyACK echoReadyACK) {}

                            @Override
                            public void onError(Throwable throwable) {}

                            @Override
                            public void onCompleted() {
                            }
                        })).start();
                    }

                    if(request.getId().equals("Ready")){
                        new Thread(() -> servers[finalServer].ready((Contract.ReadyRequest) request.getRequest(), new StreamObserver<>() {
                            @Override
                            public void onNext(Contract.EchoReadyACK echoReadyACK) {}

                            @Override
                            public void onError(Throwable throwable) {}

                            @Override
                            public void onCompleted() {
                            }
                        })).start();
                    }

                    return null;
                }).when(serverPerfectLinks[server]).process(any(RequestType.class), any(FutureCallback.class));
            }

            for (int server = 0; server < numServers; server++) {
                servers[server] = new DPASServiceImpl(serverPrivateKeys[server], server, numFaults, serverPerfectLinks, serverPublicKeys);
                servers[server].registerTestClient(getRegisterRequest(clientPublicKey, clientPrivateKey));
            }

        } catch (Exception e) {
            System.out.println("Unable to set up test: " + e.getClass());
        }
    }

    @AfterClass
    public static void cleanUp(){
        for(int server = 0; server < numServers; server++){
            servers[server].cleanPosts(Empty.newBuilder().build(), new StreamObserver<Empty>() {
                @Override
                public void onNext(Empty empty) {}

                @Override
                public void onError(Throwable throwable) {}

                @Override
                public void onCompleted() {}
            });

            servers[server].cleanGeneralPosts(Empty.newBuilder().build(), new StreamObserver<Empty>() {
                @Override
                public void onNext(Empty empty) {}

                @Override
                public void onError(Throwable throwable) {}

                @Override
                public void onCompleted() {}
            });
        }
    }

    @Test
    public void successRegister() throws InterruptedException, NoSuchAlgorithmException {
        serverPerfectLinks[numServers - 1] = mock(AuthenticatedPerfectLink.class);

        doAnswer((Answer<Void>) invocation -> {
            RequestType request = (RequestType) invocation.getArguments()[0];

            if(request.getId().equals("Echo")){
                new Thread(() -> servers[numServers - 1].echo((Contract.EchoRequest) request.getRequest(), new StreamObserver<>() {
                    @Override
                    public void onNext(Contract.EchoReadyACK echoReadyACK) {}

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {
                    }
                })).start();
            }

            if(request.getId().equals("Ready")){
                new Thread(() -> servers[numServers - 1].ready((Contract.ReadyRequest) request.getRequest(), new StreamObserver<>() {
                    @Override
                    public void onNext(Contract.EchoReadyACK echoReadyACK) {}

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {
                    }
                })).start();
            }

            return null;
        }).when(serverPerfectLinks[numServers - 1]).process(any(RequestType.class), any(FutureCallback.class));

        CountDownLatch countDownLatch = new CountDownLatch(numServers);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.genKeyPair();
        PublicKey testClientPublicKey = kp.getPublic();
        PrivateKey testClientPrivateKey = kp.getPrivate();

        Contract.RegisterRequest registerRequest = getRegisterRequest(testClientPublicKey, testClientPrivateKey);

        for(int server = 0; server < numServers; server++){
            int finalServer = server;
            new Thread(() -> servers[finalServer].register(registerRequest, new StreamObserver<Contract.ACK>() {
                @Override
                public void onNext(Contract.ACK ack) {}

                @Override
                public void onError(Throwable throwable) {
                    fail("Server " + finalServer + " failed to register");
                }

                @Override
                public void onCompleted() {
                    countDownLatch.countDown();
                }
            })).start();
        }

        boolean timeout = countDownLatch.await(45, TimeUnit.SECONDS);

        Assert.assertTrue(timeout);

        Thread.sleep(1000);

        for(int server = 0; server < numServers; server++){
            AuthenticatedDoubleEchoBroadcast adeb = servers[server].getADEB(new RegisterRequest(registerRequest));
            int numEchos = adeb.getNumEchos();
            int numReadys = adeb.getNumReadys();

            Assert.assertTrue("[" + server + "] Number of echos (" + (numEchos + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numEchos + 1) >= minResponses);
            Assert.assertTrue("[" + server + "] Number of readys (" + (numReadys + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numReadys + 1) >= minResponses);
            servers[server].clientRegisteredState(registerRequest, new StreamObserver<Contract.TestsResponse>() {
                @Override
                public void onNext(Contract.TestsResponse testsResponse) {
                    Assert.assertTrue(testsResponse.getTestResult());
                }

                @Override
                public void onError(Throwable throwable) {}

                @Override
                public void onCompleted() {}
            });
        }
    }

    @Test
    public void successPost() throws InterruptedException {
        serverPerfectLinks[numServers - 1] = mock(AuthenticatedPerfectLink.class);

        doAnswer((Answer<Void>) invocation -> {
            RequestType request = (RequestType) invocation.getArguments()[0];

            if(request.getId().equals("Echo")){
                new Thread(() -> servers[numServers - 1].echo((Contract.EchoRequest) request.getRequest(), new StreamObserver<>() {
                    @Override
                    public void onNext(Contract.EchoReadyACK echoReadyACK) {}

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {
                    }
                })).start();
            }

            if(request.getId().equals("Ready")){
                new Thread(() -> servers[numServers - 1].ready((Contract.ReadyRequest) request.getRequest(), new StreamObserver<>() {
                    @Override
                    public void onNext(Contract.EchoReadyACK echoReadyACK) {}

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {
                    }
                })).start();
            }

            return null;
        }).when(serverPerfectLinks[numServers - 1]).process(any(RequestType.class), any(FutureCallback.class));

        CountDownLatch countDownLatch = new CountDownLatch(numServers);

        Contract.PostRequest postRequest = getPostRequest(clientPublicKey, clientPrivateKey, "post".toCharArray(), new String[0], postFreshness++, "0");

        for(int server = 0; server < numServers; server++){
            int finalServer = server;
            new Thread(() -> servers[finalServer].post(postRequest, new StreamObserver<Contract.ACK>() {
                @Override
                public void onNext(Contract.ACK ack) {}

                @Override
                public void onError(Throwable throwable) {
                    fail("Server " + finalServer + " failed to post");
                }

                @Override
                public void onCompleted() {
                    countDownLatch.countDown();
                }
            })).start();
        }

        boolean timeout = countDownLatch.await(45, TimeUnit.SECONDS);

        Assert.assertTrue(timeout);

        Thread.sleep(500);

        for(int server = 0; server < numServers; server++){
            AuthenticatedDoubleEchoBroadcast adeb = servers[server].getADEB(new PostRequest(postRequest, "PostRequest"));
            int numEchos = adeb.getNumEchos();
            int numReadys = adeb.getNumReadys();

            Assert.assertTrue("[" + server + "] Number of echos (" + (numEchos + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numEchos + 1) >= minResponses);
            Assert.assertTrue("[" + server + "] Number of readys (" + (numReadys + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numReadys + 1) >= minResponses);
            servers[server].postState(postRequest, new StreamObserver<Contract.TestsResponse>() {
                @Override
                public void onNext(Contract.TestsResponse testsResponse) {
                    Assert.assertTrue(testsResponse.getTestResult());
                }

                @Override
                public void onError(Throwable throwable) {}

                @Override
                public void onCompleted() {}
            });
        }
    }

    @Test
    public void successPostGeneral() throws InterruptedException {
        serverPerfectLinks[numServers - 1] = mock(AuthenticatedPerfectLink.class);

        doAnswer((Answer<Void>) invocation -> {
            RequestType request = (RequestType) invocation.getArguments()[0];

            if(request.getId().equals("Echo")){
                new Thread(() -> servers[numServers - 1].echo((Contract.EchoRequest) request.getRequest(), new StreamObserver<>() {
                    @Override
                    public void onNext(Contract.EchoReadyACK echoReadyACK) {}

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {
                    }
                })).start();
            }

            if(request.getId().equals("Ready")){
                new Thread(() -> servers[numServers - 1].ready((Contract.ReadyRequest) request.getRequest(), new StreamObserver<>() {
                    @Override
                    public void onNext(Contract.EchoReadyACK echoReadyACK) {}

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {
                    }
                })).start();
            }

            return null;
        }).when(serverPerfectLinks[numServers - 1]).process(any(RequestType.class), any(FutureCallback.class));

        CountDownLatch countDownLatch = new CountDownLatch(numServers);

        Contract.PostRequest postRequest = getPostRequest(clientPublicKey, clientPrivateKey, "post".toCharArray(), new String[0], postGeneralFreshness++, "1");

        for(int server = 0; server < numServers; server++){
            int finalServer = server;
            new Thread(() -> servers[finalServer].postGeneral(postRequest, new StreamObserver<Contract.ACK>() {
                @Override
                public void onNext(Contract.ACK ack) {}

                @Override
                public void onError(Throwable throwable) {
                    fail("Server " + finalServer + " failed to post to general board");
                }

                @Override
                public void onCompleted() {
                    countDownLatch.countDown();
                }
            })).start();
        }

        boolean timeout = countDownLatch.await(45, TimeUnit.SECONDS);

        Assert.assertTrue(timeout);

        Thread.sleep(500);

        for(int server = 0; server < numServers; server++){
            AuthenticatedDoubleEchoBroadcast adeb = servers[server].getADEB(new PostRequest(postRequest, "PostGeneralRequest"));
            int numEchos = adeb.getNumEchos();
            int numReadys = adeb.getNumReadys();

            Assert.assertTrue("[" + server + "] Number of echos (" + (numEchos + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numEchos + 1) >= minResponses);
            Assert.assertTrue("[" + server + "] Number of readys (" + (numReadys + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numReadys + 1) >= minResponses);
            servers[server].postGeneralState(postRequest, new StreamObserver<Contract.TestsResponse>() {
                @Override
                public void onNext(Contract.TestsResponse testsResponse) {
                    Assert.assertTrue(testsResponse.getTestResult());
                }

                @Override
                public void onError(Throwable throwable) {}

                @Override
                public void onCompleted() {}
            });
        }
    }

    @Test
    public void successIteratedRegister() throws InterruptedException, NoSuchAlgorithmException {
        serverPerfectLinks[numServers - 1] = mock(AuthenticatedPerfectLink.class);

        doAnswer((Answer<Void>) invocation -> {
            return null;
        }).when(serverPerfectLinks[numServers - 1]).process(any(RequestType.class), any(FutureCallback.class));

        CountDownLatch countDownLatch = new CountDownLatch(numServers - 1);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(4096);
        KeyPair kp = kpg.genKeyPair();
        PublicKey testClientPublicKey = kp.getPublic();
        PrivateKey testClientPrivateKey = kp.getPrivate();

        Contract.RegisterRequest registerRequest = getRegisterRequest(testClientPublicKey, testClientPrivateKey);

        for(int server = 0; server < minResponses - 1; server++){
            if(seeBehaviour) System.out.println("\n\nClient sent request to " + server);
            int finalServer = server;
            new Thread(() -> servers[finalServer].register(registerRequest, new StreamObserver<Contract.ACK>() {
                @Override
                public void onNext(Contract.ACK ack) {}

                @Override
                public void onError(Throwable throwable) {
                    fail("Server " + finalServer + " failed to register");
                }

                @Override
                public void onCompleted() {
                    countDownLatch.countDown();
                }
            })).start();

            for(int i = 0; i < numServers; i++){
                servers[i].clientRegisteredState(registerRequest, new StreamObserver<Contract.TestsResponse>() {
                    @Override
                    public void onNext(Contract.TestsResponse testsResponse) {
                        Assert.assertFalse("Shouldnt have been registered yet", testsResponse.getTestResult());
                    }

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {}
                });
            }

            if(seeBehaviour) Thread.sleep(10000);
        }

        if(seeBehaviour) System.out.println("\n\nClient sent request to " + (minResponses - 1));

        new Thread(() -> servers[minResponses - 1].register(registerRequest, new StreamObserver<Contract.ACK>() {
            @Override
            public void onNext(Contract.ACK ack) {}

            @Override
            public void onError(Throwable throwable) {
                fail("Server " + minResponses + " failed to register");
            }

            @Override
            public void onCompleted() {
                countDownLatch.countDown();
            }
        })).start();

        boolean timeout = countDownLatch.await(45, TimeUnit.SECONDS);

        Assert.assertTrue(timeout);

        Thread.sleep(1000);

        for(int server = 0; server < numServers - 1; server++){
            AuthenticatedDoubleEchoBroadcast adeb = servers[server].getADEB(new RegisterRequest(registerRequest));
            int numEchos = adeb.getNumEchos();
            int numReadys = adeb.getNumReadys();

            Assert.assertTrue("[" + server + "] Number of echos (" + (numEchos + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numEchos + 1) >= minResponses);
            Assert.assertTrue("[" + server + "] Number of readys (" + (numReadys + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numReadys + 1) >= minResponses);
            servers[server].clientRegisteredState(registerRequest, new StreamObserver<Contract.TestsResponse>() {
                @Override
                public void onNext(Contract.TestsResponse testsResponse) {
                    Assert.assertTrue(testsResponse.getTestResult());
                }

                @Override
                public void onError(Throwable throwable) {}

                @Override
                public void onCompleted() {}
            });
        }
    }

    @Test
    public void successIteratedPost() throws InterruptedException {
        serverPerfectLinks[numServers - 1] = mock(AuthenticatedPerfectLink.class);

        doAnswer((Answer<Void>) invocation -> {
            return null;
        }).when(serverPerfectLinks[numServers - 1]).process(any(RequestType.class), any(FutureCallback.class));

        CountDownLatch countDownLatch = new CountDownLatch(numServers - 1);

        Contract.PostRequest postRequest = getPostRequest(clientPublicKey, clientPrivateKey, "post".toCharArray(), new String[0], postFreshness++, "0");

        for(int server = 0; server < minResponses - 1; server++){
            if(seeBehaviour) System.out.println("\n\nClient sent request to " + server);
            int finalServer = server;
            new Thread(() -> servers[finalServer].post(postRequest, new StreamObserver<Contract.ACK>() {
                @Override
                public void onNext(Contract.ACK ack) {}

                @Override
                public void onError(Throwable throwable) {
                    fail("Server " + finalServer + " failed to post");
                }

                @Override
                public void onCompleted() {
                    countDownLatch.countDown();
                }
            })).start();

            for(int i = 0; i < numServers; i++){
                servers[i].postState(postRequest, new StreamObserver<Contract.TestsResponse>() {
                    @Override
                    public void onNext(Contract.TestsResponse testsResponse) {
                        Assert.assertFalse("Shouldnt have been posted yet", testsResponse.getTestResult());
                    }

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {}
                });
            }

            if(seeBehaviour) Thread.sleep(10000);
        }

        if(seeBehaviour) System.out.println("\n\nClient sent request to " + (minResponses - 1));

        new Thread(() -> servers[minResponses - 1].post(postRequest, new StreamObserver<Contract.ACK>() {
            @Override
            public void onNext(Contract.ACK ack) {}

            @Override
            public void onError(Throwable throwable) {
                fail("Server " + minResponses + " failed to register");
            }

            @Override
            public void onCompleted() {
                countDownLatch.countDown();
            }
        })).start();

        boolean timeout = countDownLatch.await(45, TimeUnit.SECONDS);

        Assert.assertTrue(timeout);

        Thread.sleep(1000);

        for(int server = 0; server < numServers - 1; server++){
            AuthenticatedDoubleEchoBroadcast adeb = servers[server].getADEB(new PostRequest(postRequest, "PostRequest"));
            int numEchos = adeb.getNumEchos();
            int numReadys = adeb.getNumReadys();

            Assert.assertTrue("[" + server + "] Number of echos (" + (numEchos + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numEchos + 1) >= minResponses);
            Assert.assertTrue("[" + server + "] Number of readys (" + (numReadys + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numReadys + 1) >= minResponses);
            servers[server].postState(postRequest, new StreamObserver<Contract.TestsResponse>() {
                @Override
                public void onNext(Contract.TestsResponse testsResponse) {
                    Assert.assertTrue(testsResponse.getTestResult());
                }

                @Override
                public void onError(Throwable throwable) {}

                @Override
                public void onCompleted() {}
            });
        }
    }

    @Test
    public void successIteratedPostGeneral() throws InterruptedException {
        serverPerfectLinks[numServers - 1] = mock(AuthenticatedPerfectLink.class);

        doAnswer((Answer<Void>) invocation -> {
            return null;
        }).when(serverPerfectLinks[numServers - 1]).process(any(RequestType.class), any(FutureCallback.class));

        CountDownLatch countDownLatch = new CountDownLatch(numServers - 1);

        Contract.PostRequest postRequest = getPostRequest(clientPublicKey, clientPrivateKey, "post".toCharArray(), new String[0], postGeneralFreshness++, "1");

        for(int server = 0; server < minResponses - 1; server++){
            if(seeBehaviour) System.out.println("\n\nClient sent request to " + server);
            int finalServer = server;
            new Thread(() -> servers[finalServer].postGeneral(postRequest, new StreamObserver<Contract.ACK>() {
                @Override
                public void onNext(Contract.ACK ack) {}

                @Override
                public void onError(Throwable throwable) {
                    fail("Server " + finalServer + " failed to post to general board");
                }

                @Override
                public void onCompleted() {
                    countDownLatch.countDown();
                }
            })).start();

            for(int i = 0; i < numServers; i++){
                servers[i].postGeneralState(postRequest, new StreamObserver<Contract.TestsResponse>() {
                    @Override
                    public void onNext(Contract.TestsResponse testsResponse) {
                        Assert.assertFalse("Shouldnt have been registered yet", testsResponse.getTestResult());
                    }

                    @Override
                    public void onError(Throwable throwable) {}

                    @Override
                    public void onCompleted() {}
                });
            }

            if(seeBehaviour) Thread.sleep(10000);
        }

        if(seeBehaviour) System.out.println("\n\nClient sent request to " + (minResponses - 1));

        new Thread(() -> servers[minResponses - 1].postGeneral(postRequest, new StreamObserver<Contract.ACK>() {
            @Override
            public void onNext(Contract.ACK ack) {}

            @Override
            public void onError(Throwable throwable) {
                fail("Server " + minResponses + " failed to register");
            }

            @Override
            public void onCompleted() {
                countDownLatch.countDown();
            }
        })).start();

        boolean timeout = countDownLatch.await(45, TimeUnit.SECONDS);
        Assert.assertTrue(timeout);

        Thread.sleep(1000);

        for(int server = 0; server < numServers - 1; server++){
            AuthenticatedDoubleEchoBroadcast adeb = servers[server].getADEB(new PostRequest(postRequest, "PostGeneralRequest"));
            int numEchos = adeb.getNumEchos();
            int numReadys = adeb.getNumReadys();

            Assert.assertTrue("[" + server + "] Number of echos (" + (numEchos + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numEchos + 1) >= minResponses);
            Assert.assertTrue("[" + server + "] Number of readys (" + (numReadys + 1) + ") should be greater than minimum responses (" + minResponses + ")", (numReadys + 1) >= minResponses);
            servers[server].postGeneralState(postRequest, new StreamObserver<Contract.TestsResponse>() {
                @Override
                public void onNext(Contract.TestsResponse testsResponse) {
                    Assert.assertTrue(testsResponse.getTestResult());
                }

                @Override
                public void onError(Throwable throwable) {}

                @Override
                public void onCompleted() {}
            });
        }
    }



    private static Contract.RegisterRequest getRegisterRequest(PublicKey clientPublicKeyKey, PrivateKey clientPrivateKey){
        /* Serializes key and changes to ByteString */
        byte[] publicKey = SerializationUtils.serialize(clientPublicKeyKey);
        byte[] signature = SignatureHandler.publicSign(publicKey, clientPrivateKey);

        /* Prepare request */
        return Contract.RegisterRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setSignature(ByteString.copyFrom(signature)).build();
    }

    private Contract.PostRequest getPostRequest(PublicKey clientPublicKey, PrivateKey clientPrivateKey, char[] message, String[] references, long freshness, String boardID) {
        byte[] publicKey = SerializationUtils.serialize(clientPublicKey);
        String post = new String(message);
        byte[] announcements = SerializationUtils.serialize(references);

        byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, post.getBytes(), announcements, Longs.toByteArray(freshness), boardID.getBytes()), clientPrivateKey);

        return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setBoard(boardID).setFreshness(freshness).build();
    }

}
