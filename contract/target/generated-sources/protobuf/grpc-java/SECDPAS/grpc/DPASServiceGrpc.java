package SECDPAS.grpc;

import static io.grpc.MethodDescriptor.generateFullMethodName;
import static io.grpc.stub.ClientCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ClientCalls.asyncClientStreamingCall;
import static io.grpc.stub.ClientCalls.asyncServerStreamingCall;
import static io.grpc.stub.ClientCalls.asyncUnaryCall;
import static io.grpc.stub.ClientCalls.blockingServerStreamingCall;
import static io.grpc.stub.ClientCalls.blockingUnaryCall;
import static io.grpc.stub.ClientCalls.futureUnaryCall;
import static io.grpc.stub.ServerCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ServerCalls.asyncClientStreamingCall;
import static io.grpc.stub.ServerCalls.asyncServerStreamingCall;
import static io.grpc.stub.ServerCalls.asyncUnaryCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedStreamingCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall;

/**
 * <pre>
 * Defining a Service, a Service can have multiple RPC operations
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.27.2)",
    comments = "Source: Contract.proto")
public final class DPASServiceGrpc {

  private DPASServiceGrpc() {}

  public static final String SERVICE_NAME = "SECDPAS.grpc.DPASService";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<SECDPAS.grpc.Contract.HelloRequest,
      SECDPAS.grpc.Contract.HelloResponse> getGreetingMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "greeting",
      requestType = SECDPAS.grpc.Contract.HelloRequest.class,
      responseType = SECDPAS.grpc.Contract.HelloResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<SECDPAS.grpc.Contract.HelloRequest,
      SECDPAS.grpc.Contract.HelloResponse> getGreetingMethod() {
    io.grpc.MethodDescriptor<SECDPAS.grpc.Contract.HelloRequest, SECDPAS.grpc.Contract.HelloResponse> getGreetingMethod;
    if ((getGreetingMethod = DPASServiceGrpc.getGreetingMethod) == null) {
      synchronized (DPASServiceGrpc.class) {
        if ((getGreetingMethod = DPASServiceGrpc.getGreetingMethod) == null) {
          DPASServiceGrpc.getGreetingMethod = getGreetingMethod =
              io.grpc.MethodDescriptor.<SECDPAS.grpc.Contract.HelloRequest, SECDPAS.grpc.Contract.HelloResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "greeting"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  SECDPAS.grpc.Contract.HelloRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  SECDPAS.grpc.Contract.HelloResponse.getDefaultInstance()))
              .setSchemaDescriptor(new DPASServiceMethodDescriptorSupplier("greeting"))
              .build();
        }
      }
    }
    return getGreetingMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static DPASServiceStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<DPASServiceStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<DPASServiceStub>() {
        @java.lang.Override
        public DPASServiceStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new DPASServiceStub(channel, callOptions);
        }
      };
    return DPASServiceStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static DPASServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<DPASServiceBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<DPASServiceBlockingStub>() {
        @java.lang.Override
        public DPASServiceBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new DPASServiceBlockingStub(channel, callOptions);
        }
      };
    return DPASServiceBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static DPASServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<DPASServiceFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<DPASServiceFutureStub>() {
        @java.lang.Override
        public DPASServiceFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new DPASServiceFutureStub(channel, callOptions);
        }
      };
    return DPASServiceFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   * Defining a Service, a Service can have multiple RPC operations
   * </pre>
   */
  public static abstract class DPASServiceImplBase implements io.grpc.BindableService {

    /**
     * <pre>
     * Define a RPC operation
     * </pre>
     */
    public void greeting(SECDPAS.grpc.Contract.HelloRequest request,
        io.grpc.stub.StreamObserver<SECDPAS.grpc.Contract.HelloResponse> responseObserver) {
      asyncUnimplementedUnaryCall(getGreetingMethod(), responseObserver);
    }

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
          .addMethod(
            getGreetingMethod(),
            asyncUnaryCall(
              new MethodHandlers<
                SECDPAS.grpc.Contract.HelloRequest,
                SECDPAS.grpc.Contract.HelloResponse>(
                  this, METHODID_GREETING)))
          .build();
    }
  }

  /**
   * <pre>
   * Defining a Service, a Service can have multiple RPC operations
   * </pre>
   */
  public static final class DPASServiceStub extends io.grpc.stub.AbstractAsyncStub<DPASServiceStub> {
    private DPASServiceStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected DPASServiceStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new DPASServiceStub(channel, callOptions);
    }

    /**
     * <pre>
     * Define a RPC operation
     * </pre>
     */
    public void greeting(SECDPAS.grpc.Contract.HelloRequest request,
        io.grpc.stub.StreamObserver<SECDPAS.grpc.Contract.HelloResponse> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(getGreetingMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * <pre>
   * Defining a Service, a Service can have multiple RPC operations
   * </pre>
   */
  public static final class DPASServiceBlockingStub extends io.grpc.stub.AbstractBlockingStub<DPASServiceBlockingStub> {
    private DPASServiceBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected DPASServiceBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new DPASServiceBlockingStub(channel, callOptions);
    }

    /**
     * <pre>
     * Define a RPC operation
     * </pre>
     */
    public SECDPAS.grpc.Contract.HelloResponse greeting(SECDPAS.grpc.Contract.HelloRequest request) {
      return blockingUnaryCall(
          getChannel(), getGreetingMethod(), getCallOptions(), request);
    }
  }

  /**
   * <pre>
   * Defining a Service, a Service can have multiple RPC operations
   * </pre>
   */
  public static final class DPASServiceFutureStub extends io.grpc.stub.AbstractFutureStub<DPASServiceFutureStub> {
    private DPASServiceFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected DPASServiceFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new DPASServiceFutureStub(channel, callOptions);
    }

    /**
     * <pre>
     * Define a RPC operation
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<SECDPAS.grpc.Contract.HelloResponse> greeting(
        SECDPAS.grpc.Contract.HelloRequest request) {
      return futureUnaryCall(
          getChannel().newCall(getGreetingMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_GREETING = 0;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final DPASServiceImplBase serviceImpl;
    private final int methodId;

    MethodHandlers(DPASServiceImplBase serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_GREETING:
          serviceImpl.greeting((SECDPAS.grpc.Contract.HelloRequest) request,
              (io.grpc.stub.StreamObserver<SECDPAS.grpc.Contract.HelloResponse>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  private static abstract class DPASServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    DPASServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return SECDPAS.grpc.Contract.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("DPASService");
    }
  }

  private static final class DPASServiceFileDescriptorSupplier
      extends DPASServiceBaseDescriptorSupplier {
    DPASServiceFileDescriptorSupplier() {}
  }

  private static final class DPASServiceMethodDescriptorSupplier
      extends DPASServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final String methodName;

    DPASServiceMethodDescriptorSupplier(String methodName) {
      this.methodName = methodName;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.MethodDescriptor getMethodDescriptor() {
      return getServiceDescriptor().findMethodByName(methodName);
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (DPASServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new DPASServiceFileDescriptorSupplier())
              .addMethod(getGreetingMethod())
              .build();
        }
      }
    }
    return result;
  }
}
