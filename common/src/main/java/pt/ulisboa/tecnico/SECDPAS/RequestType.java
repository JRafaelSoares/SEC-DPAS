package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;

abstract class RequestType<T>{
    private String id;

    public RequestType(String id){
        this.id = id;
    }

    public String getId() {
        return id;
    }

    public abstract T getRequest();
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

}

class RegisterRequest extends RequestType{
    private Contract.RegisterRequest request;

    public RegisterRequest(Contract.RegisterRequest request){
        super("RegisterRequest");
        this.request = request;
    }

    public Contract.RegisterRequest getRequest(){
        return request;
    }

}