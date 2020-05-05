package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

abstract class RequestType<T> implements Serializable {
    private String id;

    public RequestType(String id){
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public abstract T getRequest();

    public abstract boolean equals(Object request);
    public abstract int hashCode();
}

class PostRequest extends RequestType<Contract.PostRequest>{
    private Contract.PostRequest request;

    public PostRequest(Contract.PostRequest request, String id){
        super(id);
        this.request = request;
    }

    public Contract.PostRequest getRequest(){
        return request;
    }

    public boolean equals(Object request){
        if(request instanceof PostRequest){
            Contract.PostRequest clientRequest = ((PostRequest) request).getRequest();

            return Arrays.compare(clientRequest.getPublicKey().toByteArray(), this.request.getPublicKey().toByteArray()) == 0 &&
                   clientRequest.getMessage().equals(this.request.getMessage()) &&
                   Arrays.compare(clientRequest.getMessageSignature().toByteArray(), this.request.getMessageSignature().toByteArray()) == 0 &&
                   Arrays.compare(clientRequest.getAnnouncements().toByteArray(), this.request.getAnnouncements().toByteArray()) == 0 &&
                   clientRequest.getBoard().equals(this.request.getBoard()) &&
                   clientRequest.getFreshness() == this.request.getFreshness();
        }

        return false;
    }

    @Override
    public int hashCode() {
        return request.hashCode();
    }
}

class ReadRequest extends RequestType<Contract.ReadRequest>{
    private Contract.ReadRequest request;

    public ReadRequest(Contract.ReadRequest request, String id){
        super(id);
        this.request = request;
    }

    public Contract.ReadRequest getRequest(){
        return request;
    }

    public boolean equals(Object request){
        if(request instanceof ReadRequest){
            Contract.ReadRequest clientRequest = ((ReadRequest) request).getRequest();

            return Arrays.compare(clientRequest.getTargetPublicKey().toByteArray(), this.request.getTargetPublicKey().toByteArray()) == 0 &&
                   Arrays.compare(clientRequest.getClientPublicKey().toByteArray(), this.request.getClientPublicKey().toByteArray()) == 0 &&
                   clientRequest.getNumber() == this.request.getNumber() &&
                   clientRequest.getFreshness() == this.request.getFreshness() &&
                   Arrays.compare(clientRequest.getSignature().toByteArray(), this.request.getSignature().toByteArray()) == 0;
        }

        return false;
    }

    @Override
    public int hashCode() {
        return request.hashCode();
    }
}

class RegisterRequest extends RequestType<Contract.RegisterRequest>{
    private Contract.RegisterRequest request;

    public RegisterRequest(Contract.RegisterRequest request){
        super("RegisterRequest");
        this.request = request;
    }

    public Contract.RegisterRequest getRequest(){
        return request;
    }

    public boolean equals(Object request){
        if(request instanceof RegisterRequest){
            Contract.RegisterRequest clientRequest = ((RegisterRequest) request).getRequest();

            return Arrays.compare(clientRequest.getPublicKey().toByteArray(), this.request.getPublicKey().toByteArray()) == 0 &&
                   Arrays.compare(clientRequest.getSignature().toByteArray(), this.request.getSignature().toByteArray()) == 0;
        }

        return false;
    }

    @Override
    public int hashCode() {
        return request.hashCode();
    }
}

class EchoRequest extends RequestType<Contract.EchoRequest>{
    private Contract.EchoRequest request;

    public EchoRequest(Contract.EchoRequest request, String id){
        super(id);
        this.request = request;
    }

    public Contract.EchoRequest getRequest(){
        return request;
    }

    public boolean equals(Object request){
        if(request instanceof EchoRequest){
            Contract.EchoRequest clientRequest = ((EchoRequest) request).getRequest();

            return clientRequest.getServerID() == this.request.getServerID() &&
                   Arrays.compare(clientRequest.getRequest().toByteArray(), this.request.getRequest().toByteArray()) == 0 &&
                   Arrays.compare(clientRequest.getSignature().toByteArray(), this.request.getSignature().toByteArray()) == 0;
        }

        return false;
    }

    @Override
    public int hashCode() {
        return request.hashCode();
    }
}
