package com.blog.gatewayservice.grpc.config;

import com.blog.account.proto.AccountServiceGrpc;
import io.grpc.Channel;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author dai.le-anh
 * @since 10/28/2023
 */

@Configuration
public class AccountStubConfig {
    @Bean
    public AccountServiceGrpc.AccountServiceBlockingStub accountServiceBlockingStub(@Qualifier("AccountGrpcChannel")Channel channel){
        return AccountServiceGrpc.newBlockingStub(channel);
    }
}
