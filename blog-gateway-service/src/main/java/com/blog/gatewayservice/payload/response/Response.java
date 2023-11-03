package com.blog.gatewayservice.payload.response;

import com.blog.gatewayservice.common.ErrorCode;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

import java.io.Serializable;
import java.util.List;

/**
 * @author dai.le-anh
 * @since 8/16/2023
 */

@Getter
@Setter
@SuperBuilder
public class Response<T> implements Serializable {
    private boolean success;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String message;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private ErrorCode errorCode;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<ErrorDTO> errors;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private String exception;
    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private T data;
}