package pt.ulisboa.tecnico.SECDPAS;


import java.io.Serializable;
import java.security.PublicKey;
import java.util.Arrays;

public class Announcement implements Serializable {

    //Maximum 256 chars
    private char[] post;

    private String[] references;

    private PublicKey publicKey;

    private int announcementID;

    public Announcement(char[] post, PublicKey publicKey, String[] references, int announcementID){
        this.post = post;
        this.publicKey = publicKey;
        this.references = references;
        this.announcementID = announcementID;
    }

    public Announcement(char[] post, PublicKey publicKey, int announcementID){
        this(post, publicKey, new String[0], announcementID);
    }

    public char[] getPost(){
        return this.post;
    }

    public int getAnnouncementID(){
        return announcementID;
    }

    public String[] getAnnouncements(){
        return this.references;
    }

    public PublicKey getPublicKey(){
        return this.publicKey;
    }

    @Override
    public boolean equals(Object obj) {
        if(obj.getClass() != this.getClass()){
            return false;
        }
        else{

            Announcement announcement = (Announcement) obj;

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
            }
        }
    }
}
