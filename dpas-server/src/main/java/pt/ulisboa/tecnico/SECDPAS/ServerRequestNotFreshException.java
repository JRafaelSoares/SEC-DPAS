package pt.ulisboa.tecnico.SECDPAS;

public class ServerRequestNotFreshException extends Exception {

    public ServerRequestNotFreshException() {
        super();
    }

    public ServerRequestNotFreshException(String message) {
        super(message);
    }
}
