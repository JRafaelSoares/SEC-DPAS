package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.primitives.Bytes;
import com.google.common.primitives.Ints;
import com.google.common.primitives.Longs;
import com.google.protobuf.ByteString;
import org.apache.commons.lang3.SerializationUtils;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class ByzantineNNRegularRegister {

    private DPASServiceGrpc.DPASServiceFutureStub[] futureStubs;
    private PublicKey[] serverPublicKey;

    private PublicKey clientKey;
    private PrivateKey clientPrivateKey;

    private FreshnessHandler readFreshnessHandler;

    private String generalBoardId = "1";

    private int minQuorumResponses;

    public ByzantineNNRegularRegister(DPASServiceGrpc.DPASServiceFutureStub[] futureStubs, PublicKey[] serverPublicKey, PublicKey clientKey, PrivateKey clientPrivateKey, int minQuorumResponses, FreshnessHandler readFreshnessHandler){
        this.futureStubs = futureStubs;
        this.serverPublicKey = serverPublicKey;

        this.clientKey = clientKey;
        this.clientPrivateKey = clientPrivateKey;

        this.readFreshnessHandler = readFreshnessHandler;
        this.minQuorumResponses = minQuorumResponses;
    }

    public void write(char[] message, String[] references){
        Announcement[] lastAnnouncement = read(1);
        long freshness = lastAnnouncement.length > 0 ? lastAnnouncement[0].getFreshness()+1 : 0;
        new ByzantineRegularRegister().write(getLinks(freshness, this.clientKey), new PostRequest(getPostRequest(message, references, freshness), "PostGeneralRequest"), this.minQuorumResponses);
    }

    public Announcement[] read(int number){
        Announcement[] announcements = new ByzantineRegularRegister().read(getLinks(readFreshnessHandler.getFreshness(), this.clientKey), new ReadRequest(getReadGeneralRequest(number, readFreshnessHandler.getFreshness()), "ReadGeneralRequest"), minQuorumResponses, number);
        readFreshnessHandler.incrementFreshness();
        return announcements;
    }

    public Map<PublicKey, AuthenticatedPerfectLink> getLinks(long freshness, PublicKey targetClientKey){
        Map<PublicKey, AuthenticatedPerfectLink> links = new HashMap<>();

        for(int server = 0; server < serverPublicKey.length; server++){
            links.put(serverPublicKey[server], new AuthenticatedPerfectLink(futureStubs[server], freshness, serverPublicKey[server], targetClientKey));
        }

        return links;
    }

    public Contract.PostRequest getPostRequest(char[] message, String[] references, long freshness) {
        byte[] publicKey = SerializationUtils.serialize(this.clientKey);
        String post = new String(message);
        byte[] announcements = SerializationUtils.serialize(references);

        byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, post.getBytes(), announcements, Longs.toByteArray(freshness), this.generalBoardId.getBytes()), this.clientPrivateKey);

        return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setBoard(this.generalBoardId).setFreshness(freshness).build();
    }

    public Contract.ReadRequest getReadGeneralRequest(int number, long freshness){
        byte[] publicKey = SerializationUtils.serialize(this.clientKey);
        byte[] numberBytes = Ints.toByteArray(number);

        byte[] signature = SignatureHandler.publicSign(Bytes.concat(publicKey, numberBytes, Longs.toByteArray(freshness)), this.clientPrivateKey);

        return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(publicKey)).setNumber(number).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();

    }

}
