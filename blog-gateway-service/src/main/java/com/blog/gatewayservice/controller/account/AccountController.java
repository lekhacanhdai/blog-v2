package com.blog.gatewayservice.controller.account;

import com.blog.gatewayservice.grpc.service.AccountGrpcClientService;
import com.blog.gatewayservice.payload.converter.AccountGrpcResponseConverter;
import com.blog.gatewayservice.payload.response.ListDTO;
import com.blog.gatewayservice.payload.response.Response;
import com.blog.gatewayservice.payload.response.RoleDTO;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author dai.le-anh
 * @since 10/28/2023
 */


@RestController
@RequiredArgsConstructor
public class AccountController {
    private final AccountGrpcClientService accountGrpcClientService;
    private final AccountGrpcResponseConverter accountGrpcResponseConverter;

    @GetMapping("roles")
    public Response<ListDTO<RoleDTO>> listRoles(){
        var context = SecurityContextHolder.getContext().getAuthentication();
        var roles = accountGrpcClientService.listRole();
        if (roles.getSuccess()){
            return accountGrpcResponseConverter.asSuccessResponse(roles.getData());
        }
        return Response.<ListDTO<RoleDTO>>builder()
                .success(false)
                .message("Fail")
                .build();
    }
}
