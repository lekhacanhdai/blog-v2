package com.blog.account.grpc.service;

import com.blog.account.proto.ListRoleResponse;

/**
 * @author dai.le-anh
 * @since 10/27/2023
 */

public interface RoleGrpcService {
    ListRoleResponse listRole();
}
