package com.blog.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @author dai.le-anh
 * @since 12/15/2023
 */

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http.authorizeHttpRequests(authz -> authz
                        .requestMatchers(HttpMethod.GET, "/roles")
                        .hasAnyAuthority("SCOPE_blog.read")
                .anyRequest()
                .fullyAuthenticated())
                .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer
                        .withDefaults()));
        return http.build();
    }
}
