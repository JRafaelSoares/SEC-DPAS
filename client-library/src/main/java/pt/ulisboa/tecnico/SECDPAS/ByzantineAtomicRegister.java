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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ByzantineAtomicRegister {

    private DPASServiceGrpc.DPASServiceFutureStub[] futureStubs;
    private PublicKey[] serverPublicKey;

    private PublicKey clientKey;
    private PrivateKey clientPrivateKey;

    private FreshnessHandler writeFreshnessHandler;
    private FreshnessHandler readFreshnessHandler;

    private String privateBoardId = "0";
    private int minQuorumResponses;

    public ByzantineAtomicRegister(DPASServiceGrpc.DPASServiceFutureStub[] futureStubs, PublicKey[] serverPublicKey, PublicKey clientKey, PrivateKey clientPrivateKey, int minQuorumResponses, FreshnessHandler readFreshnessHandler){
        this.futureStubs = futureStubs;
        this.serverPublicKey = serverPublicKey;

        this.clientKey = clientKey;
        this.clientPrivateKey = clientPrivateKey;

        this.writeFreshnessHandler = new FreshnessHandler();
        this.readFreshnessHandler = readFreshnessHandler;
        this.minQuorumResponses = minQuorumResponses;
    }

    public void write(char[] message, String[] references){
        new ByzantineRegularRegister().write(getLinks(writeFreshnessHandler.getFreshness(), this.clientKey), new PostRequest(getPostRequest(message, references, this.writeFreshnessHandler.getFreshness()), "PostRequest"), this.minQuorumResponses);
        this.writeFreshnessHandler.incrementFreshness();
    }

    public Announcement[] read(PublicKey client, int number){
        ArrayList<Contract.ReadResponse> responses = new ByzantineRegularRegister().read(getLinks(readFreshnessHandler.getFreshness(), client), new ReadRequest(getReadRequest(client, number, this.readFreshnessHandler.getFreshness()), "ReadRequest"), this.minQuorumResponses, number);

        Announcement[] announcements = getHighestReads(responses, number);
        readFreshnessHandler.incrementFreshness();
        if(announcements != null && announcements.length > 0){
            Announcement lastAnnouncement = announcements[announcements.length-1];
            new ByzantineRegularRegister().write(getLinks(lastAnnouncement.getFreshness(), this.clientKey), new PostRequest(getPostRequest(lastAnnouncement.getPost(), lastAnnouncement.getAnnouncements(), lastAnnouncement.getFreshness()), "PostRequest"), this.minQuorumResponses);
        }
        return announcements;
    }

    private Announcement[] getHighestReads(ArrayList<Contract.ReadResponse> responses, int numberAnnouncements){

        ArrayList<Announcement> announcements = new ArrayList<>();

        long maxWrite = -1;

        for(Contract.ReadResponse response: responses){
            Announcement[] ann = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());

            for(Announcement announcement: ann){
                if(!verifyAnnouncement(announcement)){
                    continue;
                }
                announcements.add(announcement);
                if(announcement.getFreshness() > maxWrite){
                    maxWrite = announcement.getFreshness();
                }
            }
        }

        int numAnnouncementsToGet = maxWrite+1 >= numberAnnouncements && numberAnnouncements != 0 ? numberAnnouncements : (int) maxWrite+1;

        long slide = maxWrite - numAnnouncementsToGet +1;
        Announcement[] response = new Announcement[numAnnouncementsToGet];

        //TODO - This probably wont work for client + server bizantine.
        //TODO - Announcement will need to be signed by f+1 servers?

        //Inefficient AND ugly but works
        int numAnnouncements = 0;

        for(Announcement announcement: announcements){
            long position = announcement.getFreshness() - slide;
            if(announcement.getFreshness() - slide >= 0 && response[(int)position] == null){
                response[(int)position] = announcement;
                numAnnouncements++;
            }

            if(numAnnouncements == numAnnouncementsToGet){
                break;
            }
        }

        return response;
    }

    private Map<PublicKey, AuthenticatedPerfectLink> getLinks(long freshness, PublicKey targetClientKey){
        Map<PublicKey, AuthenticatedPerfectLink> links = new HashMap<>();

        for(int server = 0; server < serverPublicKey.length; server++){
            links.put(serverPublicKey[server], new AuthenticatedPerfectLink(futureStubs[server], freshness, serverPublicKey[server], targetClientKey));
        }

        return links;
    }

    private Contract.PostRequest getPostRequest(char[] message, String[] references, long freshness) {
        byte[] publicKey = SerializationUtils.serialize(this.clientKey);
        String post = new String(message);
        byte[] announcements = SerializationUtils.serialize(references);

        byte[] messageSignature = SignatureHandler.publicSign(Bytes.concat(publicKey, post.getBytes(), announcements, Longs.toByteArray(freshness), privateBoardId.getBytes()), this.clientPrivateKey);

        return Contract.PostRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey)).setMessage(post).setMessageSignature(ByteString.copyFrom(messageSignature)).setAnnouncements(ByteString.copyFrom(announcements)).setBoard(this.privateBoardId).setFreshness(freshness).build();
    }

    private Contract.ReadRequest getReadRequest(PublicKey clientTargetKey, int number, long freshness){
        byte[] targetPublicKey = SerializationUtils.serialize(clientTargetKey);
        byte[] userPublicKey = SerializationUtils.serialize(this.clientKey);

        byte[] keys = Bytes.concat(targetPublicKey, userPublicKey);
        byte[] signature = SignatureHandler.publicSign(Bytes.concat(keys, Ints.toByteArray(number), Longs.toByteArray(freshness)), this.clientPrivateKey);

        return Contract.ReadRequest.newBuilder().setClientPublicKey(ByteString.copyFrom(userPublicKey)).setTargetPublicKey(ByteString.copyFrom(targetPublicKey)).setNumber(number).setFreshness(freshness).setSignature(ByteString.copyFrom(signature)).build();
    }

    private boolean verifyAnnouncement(Announcement announcement){
        int count = 0;
        // verifySignature(serverPublicKeys[entry.getKey()], signature, entry.getValue())
        byte[] serializedAnnouncements = SerializationUtils.serialize(announcement.getAnnouncements());
        byte[] serializedPublicKey = SerializationUtils.serialize(announcement.getPublicKey());
        byte[] messageBytes = new String(announcement.getPost()).getBytes();
        byte[] freshness = Longs.toByteArray(announcement.getFreshness());
        byte[] boardType = announcement.getBoard().getBytes();

        byte[] message = Bytes.concat(serializedPublicKey, messageBytes, serializedAnnouncements, freshness, boardType);

        for(Map.Entry<Integer, byte[]> entry : announcement.getServerSignatures().entrySet()){
            if(SignatureHandler.verifyPublicSignature(message, entry.getValue(), this.serverPublicKey[entry.getKey()])){
                count++;
            }
        }

        if(count < minQuorumResponses){
            return false;
        }

        return true;
    }
}
