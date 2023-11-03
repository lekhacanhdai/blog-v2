package com.blog.gatewayservice.payload.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

/**
 * @author dai.le-anh
 * @since 8/16/2023
 */

@Getter
@Setter
@Builder
public class OnlyIdDTO {
    private Long id;
}
