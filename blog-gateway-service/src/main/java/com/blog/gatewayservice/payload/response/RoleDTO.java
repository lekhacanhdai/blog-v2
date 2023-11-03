package com.blog.gatewayservice.payload.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.RequiredArgsConstructor;

/**
 * @author dai.le-anh
 * @since 10/27/2023
 */

@Builder(builderMethodName = "newBuilder", setterPrefix = "set")
public record RoleDTO(Long roleId, String role, String description) {
}
