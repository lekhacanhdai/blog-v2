package com.blog.gatewayservice.payload.response;

import com.blog.gatewayservice.common.ErrorCode;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

/**
 * @author dai.le-anh
 * @since 8/16/2023
 */

@Getter
@Setter
public class ErrorDTO {
    private String key;

    private ErrorCode code;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String value;

    public static ErrorDTO of(String key, ErrorCode code){
        ErrorDTO inst = new ErrorDTO();
        inst.setKey(key);
        inst.setCode(code);
        return inst;
    }

    public static ErrorDTO of(String key, ErrorCode code, String value){
        ErrorDTO inst = new ErrorDTO();
        inst.setKey(key);
        inst.setCode(code);
        inst.setValue(value);
        return inst;
    }
}
