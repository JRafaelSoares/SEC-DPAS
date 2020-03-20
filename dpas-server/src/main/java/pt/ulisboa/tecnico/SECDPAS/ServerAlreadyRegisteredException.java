package pt.ulisboa.tecnico.SECDPAS;

public class ServerAlreadyRegisteredException extends Exception {

    public ServerAlreadyRegisteredException() {
        super();
    }

    public ServerAlreadyRegisteredException(String message) {
        super(message);
    }
}
