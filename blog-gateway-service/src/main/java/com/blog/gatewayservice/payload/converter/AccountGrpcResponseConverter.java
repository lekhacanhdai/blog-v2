package com.blog.gatewayservice.payload.converter;

import com.blog.account.proto.ListRoleResponse;
import com.blog.gatewayservice.payload.response.ListDTO;
import com.blog.gatewayservice.payload.response.Response;
import com.blog.gatewayservice.payload.response.RoleDTO;
import org.springframework.stereotype.Component;

import java.util.stream.Collectors;

/**
 * @author dai.le-anh
 * @since 10/28/2023
 */

@Component
public class AccountGrpcResponseConverter {
    public Response<ListDTO<RoleDTO>> asSuccessResponse(ListRoleResponse.Data data){
        return Response.<ListDTO<RoleDTO>>builder()
                .success(true)
                .data(ListDTO.<RoleDTO>builder()
                        .items(data.getRolesList().stream()
                                .map(role ->
                                        RoleDTO.newBuilder()
                                                .setRoleId(role.getRoleId())
                                                .setRole(role.getRole())
                                                .setDescription(role.getDescription())
                                                .build())
                                .collect(Collectors.toList()))
                        .totalElement((long) data.getRolesCount())
                        .build())
                .build();
    }
}
