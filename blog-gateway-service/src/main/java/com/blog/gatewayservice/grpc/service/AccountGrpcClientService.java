package com.blog.gatewayservice.grpc.service;

import com.blog.account.proto.ListRoleResponse;

/**
 * @author dai.le-anh
 * @since 10/28/2023
 */

public interface AccountGrpcClientService {
    ListRoleResponse listRole();
}
