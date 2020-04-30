package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import org.apache.commons.lang3.SerializationUtils;

import java.security.PublicKey;
import java.util.*;

public class ByzantineRegularRegister {

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

        /* Create quorum */
        Quorum<PublicKey, Contract.ReadResponse> qr = Quorum.create(calls, request, minResponses);

        try{
            qr.waitForQuorum();
            if(request.getId().equals("ReadRequest")){
                return getHighestReads(qr.getSuccesses(), numberAnnouncements);
            }else{
                return getHighestReadsGeneral(qr.getSuccesses(), numberAnnouncements);
            }
        }catch (InterruptedException e){
            System.out.println(e.getMessage());
            return null;
        }
    }

    public Announcement[] getHighestReads(HashMap<PublicKey, Contract.ReadResponse> responses, int numberAnnouncements){

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

        //Inefficient AND ugly but works
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

    public Announcement[] getHighestReadsGeneral(HashMap<PublicKey, Contract.ReadResponse> responses, int numberAnnouncements){

        List<Announcement> list = new ArrayList<>();

        for(Contract.ReadResponse response: responses.values()){
            Announcement[] announcements = SerializationUtils.deserialize(response.getAnnouncements().toByteArray());

            for(Announcement announcement: announcements){
                if(!list.contains(announcement)) {
                    list.add(announcement);
                }
            }
        }

        list.sort(new Comparator<>() {
            @Override
            public int compare(Announcement o1, Announcement o2) {
                if(o1.getFreshness() > o2.getFreshness()){
                    return 1;
                }else{
                    if(o1.getFreshness() == o2.getFreshness()){
                        if(o1.getPublicKey().toString().compareTo(o2.getPublicKey().toString()) > 0){
                            return 1;
                        }else{
                            return -1;
                        }
                    }else{
                        return -1;
                    }
                }
            }
        });

        int numAnnouncementsToGet = list.size() >= numberAnnouncements && numberAnnouncements != 0 ? numberAnnouncements : list.size();

        if(numAnnouncementsToGet == 0){
            return new Announcement[0];
        }
        list = list.subList(0, numAnnouncementsToGet);

        Announcement[] response = new Announcement[list.size()];

        for(int i=0; i<list.size(); i++){
            response[i] = list.get(i);
        }

        return response;

    }
}
