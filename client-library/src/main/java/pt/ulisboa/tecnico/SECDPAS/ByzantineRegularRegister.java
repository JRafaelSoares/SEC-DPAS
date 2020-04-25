package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import org.apache.commons.lang3.SerializationUtils;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class ByzantineRegularRegister {

    private FreshnessHandler freshnessHandler;

    public ByzantineRegularRegister(FreshnessHandler handler){
        this.freshnessHandler = handler;
    }
    public void write(Map<PublicKey, AuthenticatedPerfectLink> calls, RequestType request, int minResponses) {

        /* Create quorum */
        Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, request, minResponses);

        try{
            qr.waitForQuorum();
        }catch (InterruptedException e){
            System.out.println(e.getMessage());
        }
    }


    public Announcement[] read(Map<PublicKey, AuthenticatedPerfectLink> calls, RequestType request, int minResponses, int numberAnnouncements) {

        Quorum<PublicKey, Contract.ReadResponse> qr = Quorum.create(calls, request, minResponses);

        try{
            qr.waitForQuorum();
            //return getHighestReads(qr.getSuccesses(), numberAnnouncements);
        }catch (InterruptedException e){
            System.out.println(e.getMessage());
        }

        //Increment Read Freshness
        //Quorum Read
        //Return
        return null;
    }
    /*

    public Announcement[] getHighestReads(HashMap<PublicKey, Contract.ReadResponse> responses, int numberAnnouncements){

        int maxWrite = -1;

        for(Contract.ReadResponse response: responses.values()){
            Announcement[] announcements = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());

            for(Announcement announcement: announcements){
                if(announcement.getFreshness() > maxWrite){
                    maxWrite = announcement.getFreshness();
                }
            }
        }

        int numAnnouncementsToGet = maxWrite >= numberAnnouncements ? numberAnnouncements : maxWrite;

        Announcement[] response = new Announcement[numAnnouncementsToGet];

        for(Contract.ReadResponse response: responses.values()){
            Announcement[] announcements = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());

            for(Announcement announcement: announcements){
                if(announcement.getFreshness() > maxWrite){
                    maxWrite = announcement.getFreshness();
                }
            }
        }
        return null;
    }

    public Contract.ReadResponse getHighestValueResponse(HashMap<PublicKey, Contract.ReadResponse> responses){
        Contract.ReadResponse highestValueResponse = null;
        for( Contract.ReadResponse response : responses.values()){
            if(highestValueResponse == null){
                highestValueResponse = response;
            }

            else{

                if(response.getAnnouncements())
            }

        }
    }

    public boolean checkHighestValue(Contract.ReadResponse currentMax, Contract.ReadResponse trying){
        Announcement[] maxAnnouncements = SerializationUtils.deserialize(currentMax.getAnnouncements().toByteArray());
        Announcement[] tryingAnnouncements = SerializationUtils.deserialize(trying.getAnnouncements().toByteArray());

        //(1,N) Regular only has 1 writer, so maxLenght is always the most recent one.
        if(tryingAnnouncements.length > maxAnnouncements.length){

        }

    }
    */
}
