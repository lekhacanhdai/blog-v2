package com.blog.gatewayservice.payload.response;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.List;

/**
 * @author dai.le-anh
 * @since 8/16/2023
 */

@Getter
@Setter
@Builder
public class ListDTO<T> {
    private Long totalElement;
    private List<T> items;
}
