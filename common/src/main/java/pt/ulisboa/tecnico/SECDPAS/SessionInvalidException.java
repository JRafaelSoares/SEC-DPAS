package pt.ulisboa.tecnico.SECDPAS;

public class SessionInvalidException extends Exception {

    public SessionInvalidException(){
        super("Session is no longer valid");
    }
}
