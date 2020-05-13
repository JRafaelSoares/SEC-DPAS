package pt.ulisboa.tecnico.SECDPAS;


import java.io.Serializable;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

public class Announcement implements Serializable {

    //Maximum 256 chars
    private char[] post;

    private String[] references;

    private PublicKey publicKey;

    private String announcementID;

    private byte[] signature;
    private HashMap<Integer, byte[]> serverSignatures;

    private long freshness;

    private String board;

    public Announcement(char[] post, PublicKey publicKey, String[] references, String announcementID, byte[] signature, long freshness, String board, HashMap<Integer, byte[]> serverSignatures){
        this.post = post;
        this.publicKey = publicKey;
        this.references = references;
        this.announcementID = announcementID;
        this.signature = signature;
        this.freshness = freshness;
        this.board = board;
        this.serverSignatures = serverSignatures;
    }

    public Announcement(char[] post, PublicKey publicKey, String announcementID, byte[] signature, long freshness, String board, HashMap<Integer, byte[]> serverSignatures){
        this(post, publicKey, new String[0], announcementID, signature, freshness, board, serverSignatures);
    }

    public char[] getPost(){
        return this.post;
    }

    public String getAnnouncementID(){
        return announcementID;
    }

    public String[] getAnnouncements(){
        return this.references;
    }

    public PublicKey getPublicKey(){
        return this.publicKey;
    }

    public byte[] getSignature() {
        return signature;
    }

    public HashMap<Integer, byte[]> getServerSignatures(){
        return serverSignatures;
    }

    public long getFreshness() {
        return freshness;
    }

    @Override
    public boolean equals(Object obj) {
        if(obj.getClass() != this.getClass()){
            return false;
        }else{
            Announcement announcement = (Announcement) obj;

            return announcement.getAnnouncementID().equals(announcementID);
        }
    }


    public String getBoard() {
        return board;
    }
}
