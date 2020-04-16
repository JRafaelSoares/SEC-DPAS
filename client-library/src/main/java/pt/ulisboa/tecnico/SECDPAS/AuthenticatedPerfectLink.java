package pt.ulisboa.tecnico.SECDPAS;

import SECDPAS.grpc.Contract;
import SECDPAS.grpc.DPASServiceGrpc;
import com.google.common.util.concurrent.ListenableFuture;
import io.grpc.StatusRuntimeException;

import java.util.concurrent.ExecutionException;

public class AuthenticatedPerfectLink {

    private DPASServiceGrpc.DPASServiceFutureStub futureStub;

    AuthenticatedPerfectLink(DPASServiceGrpc.DPASServiceFutureStub futureStub){
        this.futureStub = futureStub;
    }

    public Contract.ACK register(Contract.RegisterRequest request) throws StatusRuntimeException{

        while(true){
            try{
                ListenableFuture<Contract.ACK> listenable = futureStub.register(request);
                return listenable.get();

            } catch (InterruptedException | ExecutionException e) {
                if(e.getCause() instanceof StatusRuntimeException){
                    throw (StatusRuntimeException) e.getCause();
                }
            }
        }

    }

    public Contract.ACK post(Contract.PostRequest request) throws StatusRuntimeException{
        return postAux(request, "post");
    }

    public Contract.ACK postGeneral(Contract.PostRequest request) throws StatusRuntimeException{
        return postAux(request, "postGeneral");
    }

    public Contract.ReadResponse read(Contract.ReadRequest request) throws StatusRuntimeException{
        return readAux(request, "read");
    }

    public Contract.ReadResponse readGeneral(Contract.ReadRequest request) throws StatusRuntimeException{
        return readAux(request, "readGeneral");
    }

    private Contract.ACK postAux(Contract.PostRequest request, String type) throws StatusRuntimeException{

        while(true){
            try{
                switch (type){
                    case "post":
                        return futureStub.post(request).get();
                    case "postGeneral":
                        return futureStub.postGeneral(request).get();
                }

            } catch (InterruptedException | ExecutionException e) {
                if(e.getCause() instanceof StatusRuntimeException){
                    throw (StatusRuntimeException) e.getCause();
                }
            }
        }
    }

    private Contract.ReadResponse readAux(Contract.ReadRequest request, String type) throws StatusRuntimeException{

        while(true){
            try{
                switch (type){
                    case "read":
                        return futureStub.read(request).get();
                    case "readGeneral":
                        return futureStub.readGeneral(request).get();
                }

            } catch (InterruptedException | ExecutionException e) {
                if(e.getCause() instanceof StatusRuntimeException){
                    throw (StatusRuntimeException) e.getCause();
                }
            }
        }

    }

}
