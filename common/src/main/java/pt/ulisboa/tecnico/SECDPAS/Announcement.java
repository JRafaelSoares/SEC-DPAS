package pt.ulisboa.tecnico.SECDPAS;


import java.io.Serializable;
import java.security.PublicKey;
import java.util.Arrays;

public class Announcement implements Serializable {

    //Maximum 256 chars
    private char[] post;

    private Announcement[] announcements;

    private PublicKey publicKey;

    public Announcement(char[] post, PublicKey publicKey, Announcement[] announcements){
        this.post = post;
        this.publicKey = publicKey;
        this.announcements = announcements;
    }

    public Announcement(char[] post, PublicKey publicKey){
        this(post, publicKey, new Announcement[0]);
    }

    public char[] getPost(){
        return this.post;
    }

    public Announcement[] getAnnouncements(){
        return this.announcements;
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

            if (announcement.getAnnouncements().length != this.announcements.length){
                return false;
            }
            if(announcement.getAnnouncements().length == 0 && this.announcements.length == 0){
                return (Arrays.equals(this.post, announcement.post) && this.publicKey.equals(announcement.publicKey));
            }

            else {
                boolean equalArray = true;
                for(int i = 0; i < this.announcements.length; i++){
                    if(!this.announcements[i].equals(announcement.announcements[i])){
                        equalArray = false;
                        break;
                    }
                }
                return (Arrays.equals(this.post, announcement.post) && this.publicKey.equals(announcement.publicKey) && equalArray);
            }
        }
    }
}
