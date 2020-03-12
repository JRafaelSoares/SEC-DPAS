package pt.ulisboa.tecnico.SECDPAS;


import java.io.Serializable;
import java.security.PublicKey;

public class Announcement implements Serializable {

    //Maximum 256 chars
    transient private char[] post;

    transient private Announcement[] announcements;

    transient private PublicKey publicKey;

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
            return (this.post.equals(announcement.post) && this.publicKey.equals(announcement.publicKey) && this.announcements.equals(announcement.announcements));
        }
    }
}
