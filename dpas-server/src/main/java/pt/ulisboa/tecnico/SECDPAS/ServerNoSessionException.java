package pt.ulisboa.tecnico.SECDPAS;

public class ServerNoSessionException extends Exception {

    public ServerNoSessionException() {
        super();
    }

    public ServerNoSessionException(String message) {
        super(message);
    }
}
