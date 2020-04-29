package pt.ulisboa.tecnico.SECDPAS;


import java.io.Serializable;
import java.security.PublicKey;
import java.util.Arrays;

public class Announcement implements Serializable {

    //Maximum 256 chars
    private char[] post;

    private String[] references;

    private PublicKey publicKey;

    private String announcementID;

    private byte[] signature;

    private long freshness;

    private String board;

    public Announcement(char[] post, PublicKey publicKey, String[] references, String announcementID, byte[] signature, long freshness, String board){
        this.post = post;
        this.publicKey = publicKey;
        this.references = references;
        this.announcementID = announcementID;
        this.signature = signature;
        this.freshness = freshness;
        this.board = board;
    }

    public Announcement(char[] post, PublicKey publicKey, String announcementID, byte[] signature, long freshness, String board){
        this(post, publicKey, new String[0], announcementID, signature, freshness, board);
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
            /*

            if(announcement.getPublicKey() == null && this.publicKey == null){
                return true;
            }

            if (announcement.getAnnouncements().length != this.references.length){
                return false;
            }

            if(announcement.getAnnouncements().length == 0 && this.references.length == 0){
                return (Arrays.equals(this.post, announcement.post) && this.publicKey.equals(announcement.publicKey));
            }

            else {
                boolean equalArray = true;
                for(int i = 0; i < this.references.length; i++){
                    if(!this.references[i].equals(announcement.references[i])){
                        equalArray = false;
                        break;
                    }
                }
                return (Arrays.equals(this.post, announcement.post) && this.publicKey.equals(announcement.publicKey) && equalArray);
            }*/
        }
    }


    public String getBoard() {
        return board;
    }
}
