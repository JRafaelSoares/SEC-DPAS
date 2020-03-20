package pt.ulisboa.tecnico.SECDPAS;

public class MessageNotFreshException extends Exception {

    public MessageNotFreshException(){
        super("Message not fresh");
    }
}
