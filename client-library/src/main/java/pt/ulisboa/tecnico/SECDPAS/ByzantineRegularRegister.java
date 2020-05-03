package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;

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


    public ArrayList<Contract.ReadResponse> read(Map<PublicKey, AuthenticatedPerfectLink> calls, RequestType request, int minResponses, int numberAnnouncements) {
        /* Create quorum */
        Quorum<PublicKey, Contract.ReadResponse> qr = Quorum.create(calls, request, minResponses);

        try{
            qr.waitForQuorum();
            return new ArrayList<>(qr.getSuccesses().values());

        }catch (InterruptedException e){
            System.out.println(e.getMessage());
            return null;
        }
    }
}
