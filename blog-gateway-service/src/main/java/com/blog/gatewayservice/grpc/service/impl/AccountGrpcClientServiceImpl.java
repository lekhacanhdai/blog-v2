package com.blog.gatewayservice.grpc.service.impl;

import com.blog.account.proto.AccountServiceGrpc;
import com.blog.account.proto.ListRoleResponse;
import com.blog.gatewayservice.grpc.service.AccountGrpcClientService;
import com.google.protobuf.Empty;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * @author dai.le-anh
 * @since 10/28/2023
 */

@Service
@RequiredArgsConstructor
public class AccountGrpcClientServiceImpl implements AccountGrpcClientService {
    private final AccountServiceGrpc.AccountServiceBlockingStub accountServiceBlockingStub;
    @Override
    public ListRoleResponse listRole() {
        return accountServiceBlockingStub.listRole(Empty.getDefaultInstance());
    }
}
