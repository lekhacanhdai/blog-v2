package com.blog.account.grpc.service.impl;

import com.blog.account.domain.repository.RoleRepository;
import com.blog.account.grpc.service.RoleGrpcService;
import com.blog.account.proto.ListRoleResponse;
import com.blog.account.proto.RoleResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.stream.Collectors;

/**
 * @author dai.le-anh
 * @since 10/27/2023
 */

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleGrpcService {
    private final RoleRepository roleRepository;

    @Override
    public ListRoleResponse listRole(){
        var roles = roleRepository.findAll();

        return ListRoleResponse.newBuilder()
                .setSuccess(true)
                .setData(ListRoleResponse.Data.newBuilder()
                        .addAllRoles(roles.stream()
                        .map(r -> RoleResponse.newBuilder()
                        .setRole(r.getRole())
                        .setRoleId(r.getRoleId())
                        .setDescription(r.getDescription())
                        .build())
                        .collect(Collectors.toList())))
                .build();
    }
}
