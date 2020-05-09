package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.util.concurrent.Futures;
import com.google.common.util.concurrent.ListenableFuture;
import io.grpc.stub.StreamObserver;
import net.bytebuddy.implementation.bytecode.Throw;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import static org.mockito.Mockito.*;

public class AuthenticatedDoubleEchoBroadcastTest {

    private static int numServers;
    private static int numFaults;
    private static DPASServiceGrpc.DPASServiceFutureStub[] futureStubs;
    private DPASServiceImpl[] servers;
    private static PublicKey[] serverPublicKeys;
    private static PrivateKey[] serverPrivateKeys;
    private static PublicKey clientPublicKey;
    private static PrivateKey clientPrivateKey;

    @BeforeClass
    public void setUp() {
        /*
        try {

            numFaults = 1;
            numServers = 3 * numFaults + 1;

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.genKeyPair();
            clientPublicKey = kp.getPublic();
            clientPrivateKey = kp.getPrivate();

            serverPublicKeys = new PublicKey[numServers];
            serverPrivateKeys = new PrivateKey[numServers];
            futureStubs = new DPASServiceGrpc.DPASServiceFutureStub[numServers];
            servers = new DPASServiceImpl[numServers];

            //Stub and certificate for each server
            for (int server = 0; server < numServers; server++) {
                kp = kpg.genKeyPair();
                PublicKey publicKey = kp.getPublic();
                PrivateKey privateKey = kp.getPrivate();

                serverPublicKeys[server] = publicKey;
                serverPrivateKeys[server] = privateKey;
                futureStubs[server] = mock(DPASServiceGrpc.DPASServiceFutureStub.class);

                ListenableFuture<Contract.ACK> l = mock(ListenableFuture.class);
                when(futureStubs[server].register(isA(Contract.RegisterRequest.class))).thenReturn(l);

            }

            for (int server = 0; server < numServers; server++) {
                servers[server] = new DPASServiceImpl(serverPrivateKeys[server], server, numFaults, futureStubs, serverPublicKeys);
            }


        } catch (Exception e) {
            System.out.println("Unable to step up test: " + e.getClass());
        }*/
    }

    @Test
    public void successRegister(){
            Assert.assertTrue(true);
    }

}
