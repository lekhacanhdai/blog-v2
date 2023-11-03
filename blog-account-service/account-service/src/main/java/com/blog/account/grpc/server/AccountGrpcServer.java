package com.blog.account.grpc.server;

import com.blog.account.grpc.service.RoleGrpcService;
import com.blog.account.proto.AccountGrpcError;
import com.blog.account.proto.AccountServiceGrpc;
import com.blog.account.proto.ListRoleResponse;
import com.google.protobuf.Empty;
import io.grpc.stub.StreamObserver;
import lombok.RequiredArgsConstructor;
import net.devh.boot.grpc.server.service.GrpcService;

/**
 * @author dai.le-anh
 * @since 10/27/2023
 */

@GrpcService
@RequiredArgsConstructor
public class AccountGrpcServer extends AccountServiceGrpc.AccountServiceImplBase {
    private final RoleGrpcService roleGrpcService;
    @Override
    public void listRole(Empty request, StreamObserver<ListRoleResponse> responseObserver) {
        try {
            responseObserver.onNext(roleGrpcService.listRole());
            responseObserver.onCompleted();
        } catch (Exception e){
            responseObserver.onNext(ListRoleResponse.newBuilder()
                    .setSuccess(false)
                    .setError(AccountGrpcError.newBuilder()
                            .setMessage(e.getMessage())
                            .setCode("INTERNAL_ERROR")
                            .setException(e.getClass().getSimpleName())
                            .build())
                    .build());
        }
    }
}
