package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import org.apache.commons.lang3.SerializationUtils;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;

public class ByzantineRegularRegister {

    public static void write(Map<PublicKey, AuthenticatedPerfectLink> calls, RequestType request, int minResponses) {

        /* Create quorum */
        Quorum<PublicKey, Contract.ACK> qr = Quorum.create(calls, request, minResponses);

        try{
            qr.waitForQuorum();
        }catch (InterruptedException e){
            System.out.println(e.getMessage());
        }
    }


    public static Announcement[] read(Map<PublicKey, AuthenticatedPerfectLink> calls, RequestType request, int minResponses, int numberAnnouncements) {

        /* Create quorum */
        Quorum<PublicKey, Contract.ReadResponse> qr = Quorum.create(calls, request, minResponses);

        try{
            qr.waitForQuorum();
            return getHighestReads(qr.getSuccesses(), numberAnnouncements);
        }catch (InterruptedException e){
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static Announcement[] getHighestReads(HashMap<PublicKey, Contract.ReadResponse> responses, int numberAnnouncements){

        long maxWrite = -1;

        for(Contract.ReadResponse response: responses.values()){
            Announcement[] announcements = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());

            for(Announcement announcement: announcements){
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

        //Ineficient AND ugly but works
        int numAnnouncements = 0;
        for(Contract.ReadResponse response2: responses.values()){
            Announcement[] announcements = SerializationUtils.deserialize(response2.getAnnouncements().toByteArray());

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
            if(numAnnouncements == numAnnouncementsToGet){
                break;
            }
        }
        return response;
    }
    /*

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
